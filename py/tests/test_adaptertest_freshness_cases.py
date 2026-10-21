"""The FRESH cases and the time bounds of the common cases (port of
go/adapter/adaptertest/freshness_cases_test.go)."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import timedelta
from typing import Any

from hop_top_pact.adapter import Code
from hop_top_pact.adapter.adaptertest import DEFAULT_NOW
from hop_top_pact.adapter.freshness import ReasonCode
from hop_top_pact.core.clock import BASELINE_SKEW, Artifact, max_lifetime

SKEW_SEC = BASELINE_SKEW // timedelta(seconds=1)


def by_id(at: Any) -> dict[str, Any]:
    return {c.id: c for c in at.common_cases()}


def test_freshness_cases_pin_the_profile(at: Any) -> None:
    """The FRESH cases expect what the freshness profile (spec/v1.0/profiles/freshness.md,
    sections 3.2, 5 and 6) and the draft require. CLOCK_AHEAD and RESTAMPED are
    check-specific codes with no draft 13.4 row, so they are pinned as
    check_context reason codes; package freshness spells them the same way."""
    cases = by_id(at)
    for cid, function, outcome, code in (
        ("FRESH-01.revoked-after-issuance", "resolve_agent_binding", "unusable", ""),
        ("FRESH-02.stale-snapshot", "check_context", "FAIL", "STALE_EVIDENCE"),
        ("FRESH-02.at-limit", "check_context", "PASS", "REQUIREMENT_SATISFIED"),
        ("FRESH-03.observed-ahead", "check_context", "FAIL", "CLOCK_AHEAD"),
        ("FRESH-03.at-skew", "check_context", "PASS", "REQUIREMENT_SATISFIED"),
        ("FRESH-04.pinned-revision-changed", "check_context", "FAIL", "REQUIREMENTS_CHANGED"),
        (
            "FRESH-05.binding-source-down",
            "resolve_agent_binding",
            "error",
            "DEPENDENCY_UNAVAILABLE",
        ),
        ("FRESH-05.claim-source-down", "read_native_claim", "error", "DEPENDENCY_UNAVAILABLE"),
        ("FRESH-05.check-source-down", "check_context", "UNKNOWN", "DEPENDENCY_UNAVAILABLE"),
        ("FRESH-06.restamped", "check_context", "FAIL", "RESTAMPED"),
    ):
        c = cases.get(cid)
        assert c is not None, f"no case {cid}"
        e = c.expect
        assert (e.function, e.outcome, e.reason_code) == (function, outcome, code), cid
        assert c.now is not None, f"{cid} states no now: a freshness case fixes the clock"

    for code, impl in {
        "STALE_EVIDENCE": ReasonCode.STALE_EVIDENCE,
        "CLOCK_AHEAD": ReasonCode.CLOCK_AHEAD,
        "RESTAMPED": ReasonCode.RESTAMPED,
        "REQUIREMENT_SATISFIED": ReasonCode.SATISFIED,
        "DEPENDENCY_UNAVAILABLE": ReasonCode.DEPENDENCY_UNAVAILABLE,
    }.items():
        assert impl == code, f"package freshness spells {code} as {impl!r}"


def _records(c: Any, member: str) -> list[Mapping[str, Any]]:
    state = c.native_state
    assert isinstance(state, Mapping)
    return list(state.get(member, ()))


def test_freshness_case_times(at: Any) -> None:
    """The times of the FRESH cases sit where the draft's bounds put them, as
    core.clock states the bounds: one second past the 5-second skew and exactly at
    it (draft 7.5), and a revocation inside the 60-second lifetime of a contract
    issued before it (draft 9.1, 20.1)."""
    cases = by_id(at)

    def read(cid: str, member: str) -> tuple[int, list[Mapping[str, Any]]]:
        c = cases.get(cid)
        assert c is not None, f"no case {cid}"
        assert c.now is not None, f"{cid} states no now"
        return c.now, _records(c, member)

    now, checks = read("FRESH-03.observed-ahead", "checks")
    assert len(checks) == 1
    assert checks[0]["observed_at"] == now + SKEW_SEC + 1, "now plus the skew plus one second"
    now, checks = read("FRESH-03.at-skew", "checks")
    assert len(checks) == 1
    assert checks[0]["observed_at"] == now + SKEW_SEC, "now plus the skew"

    lifetime = max_lifetime(Artifact.CONTRACT) // timedelta(seconds=1)
    now, enrollments = read("FRESH-01.revoked-after-issuance", "enrollments")
    assert len(enrollments) == 1
    age = now - enrollments[0]["status_checked_at"]
    assert 0 < age < lifetime, f"the revocation is {age} s old, want inside {lifetime} s"


def test_status_check_case_times(at: Any) -> None:
    """The COMMON-04 status-check cases sit at the bound of draft A.2: exactly at now
    plus the 5-second skew for the control, and one second past it for the case
    that must not be passed on."""
    cases = by_id(at)
    for cid, ahead, outcome in (
        ("COMMON-04.status-checked-at-skew", SKEW_SEC, "claim"),
        ("COMMON-04.future-status-checked", SKEW_SEC + 1, "error"),
    ):
        c = cases.get(cid)
        assert c is not None, f"no case {cid}"
        claims = _records(c, "claims")
        assert len(claims) == 1, f"{cid}: want one claim record"
        now = DEFAULT_NOW if c.now is None else c.now
        assert claims[0]["status_checked_at"] - now == ahead, cid
        assert c.expect.outcome == outcome, cid


def test_claim_clock_ahead_cases_require_refusal(at: Any) -> None:
    """A read_native_claim whose source observation or status time is later than now
    plus the skew is refused with DEPENDENCY_UNAVAILABLE (freshness profile,
    section 3; draft A.2, 13.4)."""
    cases = by_id(at)
    for cid in ("COMMON-04.future-observed-at", "COMMON-04.future-status-checked"):
        c = cases.get(cid)
        assert c is not None, f"no case {cid}"
        e = c.expect
        assert (e.function, e.outcome, e.reason_code) == (
            "read_native_claim",
            "error",
            Code.DEPENDENCY_UNAVAILABLE,
        ), cid
