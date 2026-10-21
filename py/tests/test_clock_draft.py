"""Lifetimes, skew and replay retention against draft section 20.1.

Port of go/core/clock/draft_test.go. It reads spec/v1.0/draft.md: it fails when
the draft is absent under PACT_REQUIRE_VECTORS=1 (make py-test) and skips
otherwise (a mirror checkout).
"""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from hop_top_pact.core import clock
from hop_top_pact.core.clock import Artifact

REPO = Path(__file__).resolve().parents[2]
DRAFT = REPO / "spec" / "v1.0" / "draft.md"
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def read_draft() -> str:
    if not DRAFT.exists():
        if os.environ.get("PACT_REQUIRE_VECTORS") == "1":
            pytest.fail(f"{DRAFT} absent under PACT_REQUIRE_VECTORS=1")
        pytest.skip("no spec/ tree (mirror checkout)")
    return DRAFT.read_text(encoding="utf-8")


def draft_duration(draft: str, item: str) -> timedelta:
    """Return the "At most N seconds|hours" value of the 20.1 baseline-limit row item."""
    m = re.search(r"(?m)^\| " + re.escape(item) + r" \| At most (\d+) (second|hour)s?\b", draft)
    assert m is not None, f'draft has no 20.1 row {item!r} of the form "At most N seconds|hours"'
    n = int(m.group(1))
    return timedelta(hours=n) if m.group(2) == "hour" else timedelta(seconds=n)


def draft_key(draft: str, key: str) -> str:
    """Return the value cell of the 20.1 metadata row for key."""
    m = re.search(r"(?m)^\| `" + re.escape(key) + r"` \| ([^|]+?) \|", draft)
    assert m is not None, f"draft has no 20.1 metadata row for {key!r}"
    return m.group(1)


def draft_seconds(draft: str, key: str) -> timedelta:
    return timedelta(seconds=int(draft_key(draft, key)))


def test_lifetimes_match_the_draft() -> None:
    draft = read_draft()
    rows = [
        ("Contract validity", Artifact.CONTRACT),
        ("Presentation validity", Artifact.PRESENTATION),
        ("Profile lifetime", Artifact.PROFILE),
        ("Evidence artifact lifetime", Artifact.EVIDENCE),
        ("Reputation snapshot lifetime", Artifact.SNAPSHOT),
        ("Outcome report validity", Artifact.OUTCOME),
    ]
    for item, a in rows:
        assert clock.max_lifetime(a) == draft_duration(draft, item), item


def test_skew_and_retention_match_the_draft() -> None:
    draft = read_draft()

    assert draft_duration(draft, "Clock skew") == clock.BASELINE_SKEW
    assert draft_seconds(draft, "clock_skew_seconds") == clock.BASELINE_SKEW
    for key, a in [
        ("contract_validity_seconds", Artifact.CONTRACT),
        ("presentation_validity_seconds", Artifact.PRESENTATION),
    ]:
        assert clock.max_lifetime(a) == draft_seconds(draft, key), key

    # replay_retention_seconds is "At least 65": iat+60+skew with the baseline
    # skew, for a presentation that lives its full 60 seconds.
    cell = draft_key(draft, "replay_retention_seconds")
    m = re.fullmatch(r"At least (\d+)", cell)
    assert m is not None, f'replay_retention_seconds cell {cell!r} is not "At least N"'
    iat = 1_700_000_000
    got = clock.replay_retention(iat + 60, iat, clock.BASELINE_SKEW) - (
        EPOCH + timedelta(seconds=iat)
    )
    assert got == timedelta(seconds=int(m.group(1)))

    # 7.5 states the same formula in prose.
    assert re.search(r"later of the artifact expiry and `iat \+ 60 \+ clock_skew`", draft), (
        "draft 7.5 no longer states the replay retention formula; revisit replay_retention"
    )
