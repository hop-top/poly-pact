"""The freshness defects of the broken adapter (Go adapters/internal/broken,
freshness.go)."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from typing import TYPE_CHECKING

from broken.defects import Defect
from hop_top_pact.adapter import BindingStatus, CheckOutcome, Code, Verdict
from hop_top_pact.adapter import freshness as fr
from hop_top_pact.adapters import memory
from hop_top_pact.adapters.memory.freshness import EPOCH, source_time
from hop_top_pact.core.clock import Artifact, max_lifetime

if TYPE_CHECKING:
    from broken.adapter import BrokenAdapter

__all__ = ["check_freshness", "freshness_state", "revoked_within_contract"]

_SECOND = timedelta(seconds=1)


def freshness_state(st: memory.State, on: frozenset[Defect]) -> memory.State:
    """st as the adapter sees it with the defects that change what it knows: limits,
    pins, sightings or outages it ignores."""
    if Defect.IGNORE_CHECK_LIMITS in on or Defect.IGNORE_PINNED_REVISION in on:
        checks = []
        for c in st.checks:
            if Defect.IGNORE_CHECK_LIMITS in on:
                c = replace(c, freshness=None)
            if Defect.IGNORE_PINNED_REVISION in on:
                c = replace(c, pinned_revision="")
            checks.append(c)
        st = replace(st, checks=tuple(checks))
    if Defect.FORGET_SIGHTINGS in on:
        st = replace(st, sightings=())
    if Defect.READ_THROUGH_OUTAGE in on:
        st = replace(st, unavailable_sources=())
    return st


def check_freshness(b: BrokenAdapter, check_id: str, out: CheckOutcome) -> CheckOutcome:
    """The outcome of the check check_id with the defects that misjudge the times of
    the record it consults."""
    if b.has(Defect.DEFER_CLOCK_AHEAD) and out.reason_code == fr.ReasonCode.CLOCK_AHEAD:
        return CheckOutcome(
            result=Verdict.UNKNOWN,
            reason_code=Code.DEPENDENCY_UNAVAILABLE.value,
            source_id=out.source_id,
        )
    rec = next((c for c in b.state().checks if c.id == check_id), None)
    if out.result != Verdict.PASS or rec is None or rec.freshness is None:
        return out
    now = (b.now() - EPOCH) // _SECOND

    def ahead(t: int | None) -> bool:
        return t is not None and t > now

    def at_limit(t: int | None, limit: int | None) -> bool:
        return t is not None and limit is not None and now - t == limit

    f = rec.freshness
    if b.has(Defect.NO_SKEW_ALLOWANCE) and (ahead(rec.observed_at) or ahead(rec.status_checked_at)):
        return CheckOutcome(
            result=Verdict.FAIL,
            reason_code=fr.ReasonCode.CLOCK_AHEAD.value,
            source_id=out.source_id,
            source_ref=out.source_ref,
        )
    if b.has(Defect.STALE_AT_LIMIT) and (
        at_limit(rec.observed_at, f.max_age_seconds)
        or at_limit(rec.status_checked_at, f.status_max_age_seconds)
    ):
        return replace(out, result=Verdict.FAIL, reason_code=fr.ReasonCode.STALE_EVIDENCE.value)
    return out


def revoked_within_contract(b: BrokenAdapter, e: memory.Enrollment) -> bool:
    """Whether the source holds e as revoked or compromised by a status it confirmed
    less than a contract lifetime ago: the change a status cached at the contract's
    issuance would not show."""
    if e.status not in (BindingStatus.REVOKED, BindingStatus.COMPROMISED):
        return False
    checked = source_time(e.status_checked_at)
    if checked is None:
        return False
    age = b.now() - checked
    return timedelta(0) <= age < max_lifetime(Artifact.CONTRACT)
