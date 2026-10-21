"""constraints.txt against pyproject.toml.

Every range in pyproject.toml is written ``name>=X,<Y``; every ranged
distribution has an exact pin in constraints.txt that satisfies its range.
The build backend is pinned exactly in [build-system].requires.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

PY_ROOT = Path(__file__).resolve().parents[1]
RANGE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)>=([0-9][0-9.]*),<([0-9][0-9.]*)$")
EXACT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([0-9][0-9.]*)$")

Version = tuple[int, ...]


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def version(s: str) -> Version:
    """A release-only PEP 440 version, zero-padded for comparison."""
    parts = tuple(int(p) for p in s.split("."))
    return parts + (0,) * (6 - len(parts))


def parse_constraints(text: str) -> dict[str, Version]:
    pins: dict[str, Version] = {}
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = EXACT.match(line)
        if m is None:
            raise ValueError(f"constraints.txt:{n}: not an exact pin: {raw!r}")
        name = normalize(m.group(1))
        if name in pins:
            raise ValueError(f"constraints.txt:{n}: {name} pinned twice")
        pins[name] = version(m.group(2))
    return pins


def range_problems(ranges: list[str], pins: dict[str, Version]) -> list[str]:
    out = []
    for r in ranges:
        m = RANGE.match(r)
        if m is None:
            out.append(f"{r!r} is not written name>=X,<Y")
            continue
        name, low, high = normalize(m.group(1)), version(m.group(2)), version(m.group(3))
        pin = pins.get(name)
        if pin is None:
            out.append(f"{name} has no pin in constraints.txt")
        elif not low <= pin < high:
            out.append(f"{name} pin {pin} outside {r!r}")
    return out


def project() -> dict[str, object]:
    return tomllib.loads((PY_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_every_constraint_satisfies_its_range() -> None:
    meta = project()["project"]
    assert isinstance(meta, dict)
    ranges = [*meta["dependencies"], *meta["optional-dependencies"]["dev"]]
    pins = parse_constraints((PY_ROOT / "constraints.txt").read_text(encoding="utf-8"))
    assert range_problems(ranges, pins) == []


def test_build_backend_pinned_exactly() -> None:
    system = project()["build-system"]
    assert isinstance(system, dict)
    requires = system["requires"]
    assert requires, "build-system requires is empty"
    assert all(EXACT.match(r) for r in requires), requires


@pytest.mark.parametrize(
    ("ranges", "pins", "needle"),
    [
        (["a>=1.2,<2"], {"a": version("2.0")}, "outside"),
        (["a>=1.2,<2"], {"a": version("1.1.9")}, "outside"),
        (["a>=1.2,<2"], {}, "no pin"),
        (["a>=1.2"], {"a": version("1.2")}, "not written"),
    ],
)
def test_range_check_negative_control(
    ranges: list[str], pins: dict[str, Version], needle: str
) -> None:
    found = range_problems(ranges, pins)
    assert len(found) == 1
    assert needle in found[0]


def test_range_check_accepts_bounds() -> None:
    assert range_problems(["a>=1.2,<2"], {"a": version("1.2")}) == []
    assert range_problems(["a>=1.2,<2"], {"a": version("1.99.9")}) == []
