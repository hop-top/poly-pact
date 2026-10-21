"""The freshness evaluator against spec/v1.0/profiles/freshness.md.

Port of go/adapter/freshness/profile_test.go: the profile's worked
evaluations, its reason-code vocabulary and its clock cross-references. It
reads the profile: it fails when the file is absent under
PACT_REQUIRE_VECTORS=1 (make py-test) and skips otherwise (a mirror
checkout).
"""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from hop_top_pact.adapter import NativeClaim
from hop_top_pact.adapter.freshness import ReasonCode, evaluate
from hop_top_pact.core import clock
from hop_top_pact.core.clock import Artifact
from hop_top_pact.core.enums import CheckStatus, Comparison, RuleSource
from hop_top_pact.core.types import FieldRule

REPO = Path(__file__).resolve().parents[2]
PROFILE = REPO / "spec" / "v1.0" / "profiles" / "freshness.md"
BASE = 1_792_080_000
NOW = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=BASE)


def read_profile() -> str:
    if not PROFILE.exists():
        if os.environ.get("PACT_REQUIRE_VECTORS") == "1":
            pytest.fail(f"{PROFILE} absent under PACT_REQUIRE_VECTORS=1")
        pytest.skip("no spec/ tree (mirror checkout)")
    return PROFILE.read_text(encoding="utf-8")


def section(doc: str, head: str) -> str:
    """The text under the heading line head, up to the next heading of the same or
    a higher level."""
    level = head.index(" ")
    start = doc.find("\n" + head + "\n")
    assert start >= 0, f"profile has no heading {head!r}"
    body = doc[start + len(head) + 2 :]
    pos = 0
    for line in body.splitlines(keepends=True):
        n = len(line) - len(line.lstrip("#"))
        if 1 <= n <= level and line[n:].startswith(" "):
            return body[:pos]
        pos += len(line)
    return body


def offset(cell: str) -> datetime | None:
    """A worked-evaluation time: seconds relative to now, or none."""
    cell = cell.strip("` ")
    if cell == "none":
        return None
    assert re.fullmatch(r"[-+]?\d+", cell), f"time cell {cell!r} is neither an offset nor none"
    return NOW + timedelta(seconds=int(cell))


def cells(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def rule(max_age: int, status_max_age: int) -> FieldRule:
    return FieldRule(
        rule_id="r",
        path="/attributes/environment/principal_id",
        schema=True,
        source=RuleSource.NATIVE,
        comparison=Comparison.EQUAL,
        allowed_issuers=(),
        native_path=None,
        max_age_seconds=max_age,
        status_max_age_seconds=status_max_age,
    )


def test_profile_worked_evaluations() -> None:
    """Every row of the profile's worked evaluations through evaluate: the
    document and the code say the same."""
    table = section(read_profile(), "### 3.3 Worked evaluations")
    row = re.compile(r"^\| `([-+]?\d+|none)` \|")
    rows = 0
    for line in table.split("\n"):
        if not row.match(line):
            continue
        c = cells(line)
        assert len(c) == 7, line
        got = NativeClaim(observed_at=offset(c[0]), status_checked_at=offset(c[1]))
        want = (CheckStatus(c[4]), ReasonCode(c[5].strip("`")))
        assert evaluate(rule(int(c[2]), int(c[3])), got, NOW) == want, line
        rows += 1
    assert rows >= 10, f"found {rows} worked evaluations (did the table format change?)"


def test_profile_reason_codes() -> None:
    """The results and decisions the profile gives each reason code."""
    table = section(read_profile(), "### 3.2 Results and reason codes")
    want = {
        ReasonCode.SATISFIED: ("PASS", "Contributes to `ADMISSIBLE`"),
        ReasonCode.STALE_EVIDENCE: ("FAIL", "`INADMISSIBLE`"),
        ReasonCode.CLOCK_AHEAD: ("FAIL", "`INADMISSIBLE`"),
        ReasonCode.RESTAMPED: ("FAIL", "`INADMISSIBLE`"),
        ReasonCode.UNSUPPORTED_REQUIREMENT: ("UNKNOWN", "`DEFERRED`"),
        ReasonCode.DEPENDENCY_UNAVAILABLE: ("UNKNOWN", "`DEFERRED`"),
    }
    got: dict[str, tuple[str, str]] = {}
    for line in table.split("\n"):
        if not line.startswith("| `"):
            continue
        c = cells(line)
        assert len(c) == 5, line
        got[c[0].strip("`")] = (c[1].strip("`"), c[2])
    for code, w in want.items():
        assert got.get(code.value) == w, code
    assert len(got) == len(want), "the profile and the package list the same codes"


def test_profile_clock_cross_references() -> None:
    """The clock constants the profile names carry the values it quotes."""
    table = section(read_profile(), "## 8. Reference implementation (informative)")
    row = re.compile(
        r"^\| `clock\.(BaselineSkew|MaxLifetime\(clock\.(\w+)\))` \| (\d+) seconds? \|"
    )
    want = {"BaselineSkew": clock.BASELINE_SKEW}
    for name, a in {
        "Contract": Artifact.CONTRACT,
        "Presentation": Artifact.PRESENTATION,
        "Evidence": Artifact.EVIDENCE,
        "Snapshot": Artifact.SNAPSHOT,
        "Outcome": Artifact.OUTCOME,
        "Profile": Artifact.PROFILE,
    }.items():
        want[name] = clock.max_lifetime(a)
    seen: set[str] = set()
    for line in table.split("\n"):
        m = row.match(line)
        if m is None:
            continue
        key = "BaselineSkew" if m[1] == "BaselineSkew" else m[2]
        assert key in want, f"profile names clock constant {key!r}, which the test does not know"
        assert timedelta(seconds=int(m[3])) == want[key], key
        seen.add(key)
    assert seen == set(want), "the profile cross-references every constant"
