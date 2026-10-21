"""Freshness, revision pins, sightings and source outages of the memory adapter's
checks (port of go/adapters/memory/freshness_unit_test.go)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from typing import Any

import pytest

from hop_top_pact.adapter import (
    AgentBinding,
    BindingStatus,
    CheckInput,
    CheckOutcome,
    ClaimContext,
    DependencyUnavailable,
    Principal,
    Realm,
    Verdict,
)
from hop_top_pact.adapters import memory as m
from hop_top_pact.core.types import OperationContext

ENV = "https://gateway.example/environments/finance"
REALM = m.Realm(tenant_id="acme", environment_id=ENV)
JKT = "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"
EMPTY_OP = OperationContext(
    operation_id="",
    environment_id="",
    principal_id="",
    action="",
    resources=(),
    method="",
    target_uri="",
    body_digest="",
    headers={},
)


def limits(max_age: int, status_max_age: int) -> m.CheckFreshness:
    return m.CheckFreshness(max_age_seconds=max_age, status_max_age_seconds=status_max_age)


def run_check(a: m.MemoryAdapter, check_id: str) -> CheckOutcome:
    return a.check_context(check_id, CheckInput(principal=Principal(), operation=EMPTY_OP))


def checks(*rows: m.CheckRecord) -> Any:
    return lambda st: replace(st, checks=rows)


def test_bounded_check_evaluation(mem: Any) -> None:
    """A check with freshness limits applies them to the record it consults before
    it reports the native verdict. The rows are the worked evaluations of section
    3.3 of the freshness profile, with the baseline skew of 5 seconds; times are
    seconds relative to now, and None is a time the source does not give."""
    t = mem.at
    P, F, U = Verdict.PASS, Verdict.FAIL, Verdict.UNKNOWN
    rows = [
        (t(-10), t(0), 30, 0, P, "REQUIREMENT_SATISFIED"),
        (t(-30), t(0), 30, 0, P, "REQUIREMENT_SATISFIED"),
        (t(-31), t(0), 30, 0, F, "STALE_EVIDENCE"),
        (t(-5), t(-1), 30, 0, F, "STALE_EVIDENCE"),
        (t(-5), t(-25), 30, 30, P, "REQUIREMENT_SATISFIED"),
        (t(-5), t(-31), 30, 30, F, "STALE_EVIDENCE"),
        (t(5), t(0), 30, 0, P, "REQUIREMENT_SATISFIED"),
        (t(6), t(0), 30, 0, F, "CLOCK_AHEAD"),
        (t(0), t(6), 30, 0, F, "CLOCK_AHEAD"),
        (t(6), t(-31), 30, 30, F, "CLOCK_AHEAD"),
        (None, t(0), 30, 0, U, "UNSUPPORTED_REQUIREMENT"),
        (t(-5), None, 30, 30, U, "UNSUPPORTED_REQUIREMENT"),
        (t(-31), None, 30, 30, F, "STALE_EVIDENCE"),
        (t(-5), t(0), 0, 0, F, "STALE_EVIDENCE"),
        (t(0), t(0), 0, 0, P, "REQUIREMENT_SATISFIED"),
    ]
    for i, (observed, checked, max_age, status_max_age, result, code) in enumerate(rows):
        a, _ = mem.new_adapter(
            checks(
                m.CheckRecord(
                    id="bounded-v1",
                    result="PASS",
                    reason_code="REQUIREMENT_SATISFIED",
                    source_id="delegation",
                    source_ref="d-1",
                    observed_at=observed,
                    status_checked_at=checked,
                    freshness=limits(max_age, status_max_age),
                )
            )
        )
        got = run_check(a, "bounded-v1")
        assert (got.result, got.reason_code) == (result, code), f"row {i}"
        assert got.source_id == "delegation", f"row {i}: the check's source"
        if code == "CLOCK_AHEAD":
            assert got.observed_at is None, f"row {i}: a time ahead of the clock is passed on"
        elif observed is not None:
            assert got.observed_at is not None
            assert (got.observed_at - mem.EPOCH).total_seconds() == observed, f"row {i}"


def test_bounded_check_keeps_a_native_failure(mem: Any) -> None:
    """A record within its limits reports the native verdict, a failure included; the
    limits only ever take a PASS away."""
    a, _ = mem.new_adapter(
        checks(
            m.CheckRecord(
                id="bounded-v1",
                result="FAIL",
                reason_code="REVOKED_EVIDENCE",
                source_id="delegation",
                observed_at=mem.at(-5),
                status_checked_at=mem.at(-1),
                freshness=limits(30, 30),
            )
        )
    )
    got = run_check(a, "bounded-v1")
    assert (got.result, got.reason_code) == (Verdict.FAIL, "REVOKED_EVIDENCE")


def test_unbounded_check_times(mem: Any) -> None:
    """Without limits a check is not evaluated for age, but a time it cannot pass on
    still defers it, as for a claim (draft A.2)."""
    ok: dict[str, Any] = {
        "result": "PASS",
        "reason_code": "REQUIREMENT_SATISFIED",
        "source_id": "s",
    }
    a, _ = mem.new_adapter(
        checks(
            m.CheckRecord(
                id="old-v1", observed_at=mem.at(-86400), status_checked_at=mem.at(-86400), **ok
            ),
            m.CheckRecord(
                id="status-at-skew-v1", observed_at=mem.at(-5), status_checked_at=mem.at(5), **ok
            ),
            m.CheckRecord(
                id="status-ahead-v1", observed_at=mem.at(-5), status_checked_at=mem.at(6), **ok
            ),
        )
    )
    assert run_check(a, "old-v1").result == Verdict.PASS
    assert run_check(a, "status-at-skew-v1").result == Verdict.PASS
    got = run_check(a, "status-ahead-v1")
    assert (got.result, got.reason_code) == (Verdict.UNKNOWN, "DEPENDENCY_UNAVAILABLE")


def test_pinned_revision(mem: Any) -> None:
    """A check pinned to a revision of its source fails with REQUIREMENTS_CHANGED when
    the source reports any other, or none."""

    def pin(check_id: str, pinned: str, revision: str) -> m.CheckRecord:
        return m.CheckRecord(
            id=check_id,
            result="PASS",
            reason_code="REQUIREMENT_SATISFIED",
            source_id="pdp",
            source_ref="dec-" + check_id,
            pinned_revision=pinned,
            revision=revision,
        )

    a, _ = mem.new_adapter(
        checks(
            pin("same-v1", "policy-7", "policy-7"),
            pin("changed-v1", "policy-7", "policy-8"),
            pin("case-v1", "policy-7", "Policy-7"),
            pin("absent-v1", "policy-7", ""),
            pin("unpinned-v1", "", "policy-8"),
        )
    )
    for check_id, want in {
        "same-v1": "REQUIREMENT_SATISFIED",
        "unpinned-v1": "REQUIREMENT_SATISFIED",
        "changed-v1": "REQUIREMENTS_CHANGED",
        "case-v1": "REQUIREMENTS_CHANGED",
        "absent-v1": "REQUIREMENTS_CHANGED",
    }.items():
        got = run_check(a, check_id)
        result = Verdict.FAIL if want == m.CODE_REQUIREMENTS_CHANGED else Verdict.PASS
        assert (got.result, got.reason_code, got.source_ref) == (result, want, "dec-" + check_id)


def test_sightings(mem: Any) -> None:
    """The guard against re-stamping starts with the sightings of the state and
    records every record a bounded check consults, keyed by source and reference
    together."""

    def bounded(check_id: str, source: str, ref: str, observed: int) -> m.CheckRecord:
        return m.CheckRecord(
            id=check_id,
            result="PASS",
            reason_code="REQUIREMENT_SATISFIED",
            source_id=source,
            source_ref=ref,
            observed_at=mem.at(observed),
            status_checked_at=mem.at(-1),
            freshness=limits(300, 30),
        )

    a, _ = mem.new_adapter(
        checks(
            bounded("restamped-v1", "delegation", "d-1", -10),
            bounded("same-time-v1", "delegation", "d-2", -100),
            bounded("earlier-v1", "delegation", "d-3", -200),
            bounded("other-source-v1", "directory", "d-1", -10),
            bounded("first-v1", "delegation", "d-4", -100),
            bounded("later-v1", "delegation", "d-4", -10),
            bounded("unguarded-v1", "delegation", "", -10),
        ),
        lambda st: replace(
            st,
            sightings=(
                m.Sighting(source_id="delegation", source_ref="d-1", observed_at=mem.at(-3600)),
                m.Sighting(source_id="delegation", source_ref="d-2", observed_at=mem.at(-100)),
                m.Sighting(source_id="delegation", source_ref="d-3", observed_at=mem.at(-150)),
            ),
        ),
    )
    for check_id, code in (
        ("restamped-v1", "RESTAMPED"),
        ("same-time-v1", "REQUIREMENT_SATISFIED"),
        ("earlier-v1", "REQUIREMENT_SATISFIED"),
        ("other-source-v1", "REQUIREMENT_SATISFIED"),
        ("first-v1", "REQUIREMENT_SATISFIED"),
        ("later-v1", "RESTAMPED"),
        ("unguarded-v1", "REQUIREMENT_SATISFIED"),
        ("restamped-v1", "RESTAMPED"),
    ):
        got = run_check(a, check_id)
        want = Verdict.FAIL if code == "RESTAMPED" else Verdict.PASS
        assert (got.result, got.reason_code) == (want, code), check_id


def test_unavailable_sources(mem: Any) -> None:
    """A record of a source that cannot answer is not read: the binding and the claim
    raise DependencyUnavailable, and the check is UNKNOWN. Other sources still
    answer."""
    ag = "https://identity.example/agents/"

    def enroll(w: str, agent: str, status: str, source: str) -> m.Enrollment:
        return m.Enrollment(
            realm=REALM,
            workload=w,
            agent_id=ag + agent,
            holder_jkt=JKT,
            status=status,
            observed_at=mem.at(-60),
            status_checked_at=mem.at(-60),
            source_id=source,
        )

    ok: dict[str, Any] = {"result": "PASS", "reason_code": "REQUIREMENT_SATISFIED"}
    # Workload "up" is shared by two agents, so the adapter supports shared
    # workloads; test_resolve_agent_binding_dedicated_workload has the default.
    a, _ = mem.new_adapter(
        lambda st: replace(
            st,
            enrollments=(
                enroll("down", "down", "ACTIVE", "registry-down"),
                enroll("revoked-down", "revoked", "REVOKED", "registry-down"),
                enroll("up", "up", "ACTIVE", "registry"),
                # Another agent of the same workload, held by the source that is down.
                enroll("up", "up-other", "ACTIVE", "registry-down"),
            ),
            approved_paths=("/roles", "/dept"),
            claims=(
                m.ClaimRecord(
                    realm=REALM,
                    principal="https://idp.example/alice",
                    path="/roles",
                    value=("approver",),
                    source_id="directory-down",
                    observed_at=mem.at(-60),
                    status_checked_at=mem.at(-30),
                ),
                m.ClaimRecord(
                    realm=REALM,
                    principal="https://idp.example/alice",
                    path="/dept",
                    value="finance",
                    source_id="directory",
                    observed_at=mem.at(-60),
                    status_checked_at=mem.at(-30),
                ),
            ),
            checks=(
                m.CheckRecord(id="down-v1", source_id="checks-down", source_ref="c-1", **ok),
                m.CheckRecord(
                    id="bounded-down-v1",
                    source_id="checks-down",
                    observed_at=mem.at(-5),
                    status_checked_at=mem.at(-1),
                    freshness=limits(300, 30),
                    **ok,
                ),
                m.CheckRecord(id="up-v1", source_id="checks", **ok),
            ),
            unavailable_sources=("registry-down", "directory-down", "checks-down"),
        ),
        shared=True,
    )
    ar = Realm(tenant_id="acme", environment_id=ENV)
    for w, agent in (("down", "down"), ("revoked-down", "revoked")):
        with pytest.raises(DependencyUnavailable):
            a.resolve_agent_binding(ar, w, ag + agent)
    # On a shared workload the agent's own records decide: the record of another
    # agent of the workload, held by the source that is down, is not read for it.
    b: AgentBinding = a.resolve_agent_binding(ar, "up", ag + "up")
    assert b.status == BindingStatus.ACTIVE
    with pytest.raises(DependencyUnavailable):
        a.resolve_agent_binding(ar, "up", ag + "up-other")
    with pytest.raises(DependencyUnavailable) as e:
        a.read_native_claim("/roles", ClaimContext(principal=mem.alice()))
    assert "directory-down" in str(e.value), "the error names the source"
    assert a.read_native_claim("/dept", ClaimContext(principal=mem.alice())).value == "finance"
    for check_id in ("down-v1", "bounded-down-v1"):
        got = run_check(a, check_id)
        assert (got.result, got.reason_code, got.source_id) == (
            Verdict.UNKNOWN,
            "DEPENDENCY_UNAVAILABLE",
            "checks-down",
        ), check_id
    assert run_check(a, "up-v1").result == Verdict.PASS


def test_freshness_state_rules(mem: Any) -> None:
    """The members the freshness rules read are complete."""
    mutations: dict[str, Callable[[m.State], m.State]] = {
        "freshness without a status limit": lambda st: replace(
            st, checks=(replace(st.checks[0], freshness=m.CheckFreshness(max_age_seconds=30)),)
        ),
        "freshness without an age limit": lambda st: replace(
            st,
            checks=(replace(st.checks[0], freshness=m.CheckFreshness(status_max_age_seconds=30)),),
        ),
        "sighting without a reference": lambda st: replace(
            st, sightings=(m.Sighting(source_id="s", observed_at=mem.at(0)),)
        ),
        "sighting without a source": lambda st: replace(
            st, sightings=(m.Sighting(source_ref="r", observed_at=mem.at(0)),)
        ),
        "sighting without a time": lambda st: replace(
            st, sightings=(m.Sighting(source_id="s", source_ref="r"),)
        ),
        "empty unavailable source": lambda st: replace(st, unavailable_sources=("",)),
    }
    for name, mutate in mutations.items():
        with pytest.raises(m.MemoryAdapterError):
            mutate(mem.state()).validate()
        assert name

    doc = b"""{"model": "common/1",
      "gateway": {"tenant_id": "acme", "environment_id": "https://gateway.example/environments/finance",
        "origin": "https://gateway.example"},
      "checks": [{"id": "c", "result": "PASS", "reason_code": "REQUIREMENT_SATISFIED",
        "source_id": "s", "source_ref": "r", "observed_at": 1, "status_checked_at": 2,
        "freshness": {"max_age_seconds": 3, "status_max_age_seconds": 4},
        "pinned_revision": "p", "revision": "q"}],
      "sightings": [{"source_id": "s", "source_ref": "r", "observed_at": 1}],
      "unavailable_sources": ["t"]}"""
    st = m.parse_state(doc)
    c = st.checks[0]
    assert c.status_checked_at == 2
    assert c.freshness == limits(3, 4)
    assert (c.pinned_revision, c.revision) == ("p", "q")
    assert len(st.sightings) == 1
    assert st.unavailable_sources == ("t",)
